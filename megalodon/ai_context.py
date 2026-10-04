"""Candidate evidence-context v1; pure validation/projection, not runtime admission.

Only synthetic callers exercise this contract. A future reviewed adapter must
authenticate and qualify inputs, then revalidate dependencies at use/retention
time. Structural validation cannot prove a source exists or a count is true.
This module must not import stores, providers, collectors, or action handlers.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from ipaddress import ip_address
import json
import re


INPUT_SCHEMA = "megalodon-ai-context-input-v1"
CONTEXT_SCHEMA = "megalodon-ai-context-v1"
MAX_INPUT_BYTES = 32768
MAX_CONTEXT_BYTES = 3072  # Reserve at least 1024 bytes of the existing 4096-byte prompt.
MAX_RECORDS = 24
MAX_SOURCES = 24
MAX_COUNT = 2**53 - 1
MAX_TIME = 253402300799
SOURCE_KINDS = {
    "accepted packet metadata": "packets",
    "suricata-eve": "flows",
    "zeek-conn": "flows",
    "zeek-sample": "flows",
}
PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "ICMPV6", "SCTP", "DNS", "OTHER", "UNKNOWN"})
TRANSPORTS = frozenset({"TCP", "UDP", "SCTP"})
FLAGS = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"})
RULES = frozenset({"PORT_SCAN", "SYN_FLOOD", "DNS_TUNNELING"})
FACTS = frozenset({"protocol", "src_port", "dst_port", "tcp_flags", "findings"})
MISSING_REASONS = frozenset({"not_collected", "not_qualified", "not_applicable"})
COVERAGE_REASONS = frozenset({"source_gap", "incomplete_window", "sensor_disagreement", "no_qualified_records"})
COMPARISON_REASONS = frozenset({"not_requested", "no_baseline", "incomplete_hours", "incompatible_sources", "source_expired", "truncated"})
REFERENCE_PATTERNS = {
    "attack": r"T[0-9]{4}(?:\.[0-9]{3})?",
    "atlas": r"AML\.T[0-9]{4}(?:\.[0-9]{3})?",
    "d3fend": r"[A-Z][A-Za-z]{0,63}",
    "owasp": r"LLM[0-9]{2}",
    "cisa-kev": r"CVE-[0-9]{4}-[0-9]{4,7}",
}


class ContextError(ValueError):
    """A fixed diagnostic, never a reflection of untrusted input."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContextError(code)


def _object(value: object, required: set | frozenset, optional: set | frozenset = frozenset()) -> dict:
    _require(type(value) is dict, "INVALID_SHAPE")
    _require(required <= value.keys() and value.keys() <= required | optional, "INVALID_FIELDS")
    return value


def _list(value: object, maximum: int) -> list:
    _require(type(value) is list and len(value) <= maximum, "INVALID_LIST")
    return value


def _integer(value: object, low: int, high: int) -> int:
    _require(type(value) is int and low <= value <= high, "INVALID_INTEGER")
    return value


def _enum(value: object, choices: object) -> str:
    _require(type(value) is str and value in choices, "UNSUPPORTED_VALUE")
    return value


def _match(value: object, pattern: str) -> str:
    _require(type(value) is str and re.fullmatch(pattern, value) is not None, "INVALID_IDENTIFIER")
    return value


def _address(value: object) -> str:
    _require(type(value) is str and 1 <= len(value) <= 45 and "%" not in value, "INVALID_SUBJECT")
    try:
        return str(ip_address(value))
    except ValueError:
        raise ContextError("INVALID_SUBJECT") from None


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _bounded_input(value: object) -> None:
    # Bound work BEFORE serialization. Exact built-in types prevent callbacks;
    # depth/node limits also reject cyclic structures without recursing forever.
    budget = 2048

    def visit(item: object, depth: int) -> None:
        nonlocal budget
        budget -= 1
        _require(budget >= 0 and depth <= 8, "INPUT_TOO_LARGE")
        if type(item) is dict:
            _require(len(item) <= 32, "INPUT_TOO_LARGE")
            for key, child in item.items():
                _require(type(key) is str and len(key) <= 64, "INVALID_FIELDS")
                visit(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= 64, "INPUT_TOO_LARGE")
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            _require(len(item) <= 128 and item.isascii() and item.isprintable(), "INVALID_TEXT")
        elif type(item) is int:
            _require(0 <= item <= MAX_COUNT, "INVALID_INTEGER")
        else:
            _require(type(item) is bool, "INVALID_TYPE")

    visit(value, 0)
    _require(len(_json(value)) <= MAX_INPUT_BYTES, "INPUT_TOO_LARGE")


def _window(value: object) -> dict:
    value = _object(value, {"start", "end"})
    start = _integer(value["start"], 0, MAX_TIME)
    end = _integer(value["end"], 0, MAX_TIME)
    _require(0 < end - start <= 3600, "INVALID_WINDOW")
    return {"start": start, "end": end}


def _source_kind(source: object, kind: object) -> tuple[str, str]:
    source = _enum(source, SOURCE_KINDS)
    _require(kind == SOURCE_KINDS[source], "INCOMPATIBLE_SOURCE")
    return source, kind


def _reference(ref: object, sources: dict, kind: str, used: set) -> str:
    ref = _match(ref, r"[a-f0-9]{32}:[1-9][0-9]{0,15}")
    segment, number = ref.split(":")
    _integer(int(number), 1, MAX_COUNT)
    _require(segment in sources and sources[segment]["kind"] == kind, "INVALID_PROVENANCE")
    used.add(segment)
    return ref


def _record(value: object, subject: str, window: dict, sources: dict, used: set) -> dict:
    row = _object(value, {"ref", "source", "scope_id", "kind", "observed_at", "src_ip", "dst_ip", "missing"}, FACTS)
    source, kind = _source_kind(row["source"], row["kind"])
    scope = _match(row["scope_id"], r"[a-f0-9]{32}")
    ref = _reference(row["ref"], sources, kind, used)
    stamp = _integer(row["observed_at"], 0, MAX_TIME)
    _require(window["start"] <= stamp < window["end"], "OUTSIDE_WINDOW")
    src, dst = _address(row["src_ip"]), _address(row["dst_ip"])
    _require(subject in (src, dst), "SUBJECT_MISMATCH")
    absent = FACTS - row.keys()
    missing = _object(row["missing"], absent)
    for field, reason in missing.items():
        _enum(reason, MISSING_REASONS)
        _require(reason != "not_applicable" or field in {"src_port", "dst_port", "tcp_flags"}, "INVALID_MISSINGNESS")
    result = {"ref": ref, "source": source, "scope_id": scope, "kind": kind, "observed_at": stamp, "missing": dict(missing)}
    protocol = row.get("protocol")
    if "protocol" in row:
        result["protocol"] = _enum(protocol, PROTOCOLS)
    for field in ("src_port", "dst_port"):
        if field in row:
            _require(protocol in TRANSPORTS, "INVALID_PROTOCOL_FACT")
            result[field] = _integer(row[field], 0, 65535)
        elif missing[field] == "not_applicable":
            _require(protocol in {"ICMP", "ICMPV6"}, "INVALID_MISSINGNESS")
    if "tcp_flags" in row:
        _require(protocol == "TCP", "INVALID_PROTOCOL_FACT")
        flags = [_enum(flag, FLAGS) for flag in _list(row["tcp_flags"], len(FLAGS))]
        _require(len(set(flags)) == len(flags), "DUPLICATE_VALUE")
        result["tcp_flags"] = sorted(flags)
    elif missing["tcp_flags"] == "not_applicable":
        _require(protocol in {"UDP", "ICMP", "ICMPV6", "SCTP"}, "INVALID_MISSINGNESS")
    if "findings" in row:
        findings = []
        for finding in _list(row["findings"], 3):
            finding = _object(finding, {"id", "rule"})
            _require(kind == "packets", "UNSUPPORTED_FINDING")
            number = _integer(finding["id"], 1, MAX_COUNT)
            findings.append({"ref": f'{ref.split(":")[0]}:finding:{number}', "rule": _enum(finding["rule"], RULES)})
        result["findings"] = findings
    return result


def _group(records: list[dict], source: str, kind: str, scope: str) -> dict:
    group = {"source": source, "scope_id": scope, "measurement": "packet_records" if kind == "packets" else "flow_records",
             "record_count": len(records), "evidence_refs": sorted(row["ref"] for row in records),
             "first_observed_at": min(row["observed_at"] for row in records),
             "last_observed_at": max(row["observed_at"] for row in records)}
    missing = {}
    # A partial field is not a complete histogram. Retain fixed missing reasons
    # rather than silently treating omitted measurements as zero.
    for field in sorted(FACTS - {"findings"}):
        reasons = sorted({row["missing"][field] for row in records if field in row["missing"]})
        if reasons:
            missing[field] = reasons
        elif field == "protocol":
            group["protocol_counts"] = dict(sorted(Counter(row[field] for row in records).items()))
        elif field in {"src_port", "dst_port"}:
            counts = Counter((row["protocol"], row[field]) for row in records)
            group[field + "_counts"] = [{"protocol": proto, "port": port, "count": n} for (proto, port), n in sorted(counts.items())]
        else:
            group["tcp_flag_counts"] = dict(sorted(Counter(flag for row in records for flag in row[field]).items()))
    missing_findings = sorted({row["missing"]["findings"] for row in records if "findings" in row["missing"]})
    if missing_findings:
        missing["findings"] = missing_findings
    group["findings"] = sorted((f for row in records for f in row.get("findings", [])), key=lambda f: f["ref"])
    group["missing"] = missing
    return group


def _comparison(value: object, subject: str, window: dict, sources: dict, used: set, groups: list, coverage: dict) -> dict:
    _require(type(value) is dict, "INVALID_SHAPE")
    state = _enum(value.get("state"), {"available", "unavailable"})
    if state == "unavailable":
        value = _object(value, {"state", "reason"})
        return {"state": state, "reason": _enum(value["reason"], COMPARISON_REASONS)}
    value = _object(value, {"state", "current", "previous"})
    _require(window["end"] - window["start"] == 3600 and window["start"] % 3600 == 0 and window["start"] >= 3600, "INELIGIBLE_COMPARISON")
    _require(not coverage["truncated"] and not set(coverage["missing"]) - {"no_qualified_records"}, "INELIGIBLE_COMPARISON")
    summaries = {}
    refs = set()
    for name, start in (("current", window["start"]), ("previous", window["start"] - 3600)):
        side = {}
        for raw in _list(value[name], 4):
            row = _object(raw, {"ref", "subject", "source", "scope_id", "kind", "start", "end", "count", "basis", "eligible"})
            key = (*_source_kind(row["source"], row["kind"]), _match(row["scope_id"], r"[a-f0-9]{32}"))
            _require(row["basis"] == "retained_record_count", "INCOMPATIBLE_COMPARISON")
            _require(key not in side and _address(row["subject"]) == subject, "INCOMPATIBLE_COMPARISON")
            _require(row["eligible"] is True and type(row["start"]) is int and type(row["end"]) is int
                     and row["start"] == start and row["end"] == start + 3600, "INELIGIBLE_COMPARISON")
            ref = _reference(row["ref"], sources, "baselines", used)
            _require(ref not in refs, "DUPLICATE_REFERENCE")
            refs.add(ref)
            side[key] = {"count": _integer(row["count"], 0, MAX_COUNT), "ref": ref}
        _require(bool(side), "INELIGIBLE_COMPARISON")
        summaries[name] = side
    current, previous = summaries["current"], summaries["previous"]
    _require(current.keys() == previous.keys(), "INCOMPATIBLE_COMPARISON")
    for group in groups:
        kind = "packets" if group["measurement"] == "packet_records" else "flows"
        key = group["source"], kind, group["scope_id"]
        _require(key in current and current[key]["count"] >= group["record_count"], "INCOMPATIBLE_COMPARISON")
    return {"state": state, "basis": "qualified_hourly_record_counts", "previous_window": {"start": window["start"] - 3600, "end": window["start"]},
            "groups": [{"source": source, "scope_id": scope, "measurement": "packet_records" if kind == "packets" else "flow_records",
                        "current_count": current[source, kind, scope]["count"], "previous_count": previous[source, kind, scope]["count"],
                        "delta": current[source, kind, scope]["count"] - previous[source, kind, scope]["count"], "eligible_hours": 2,
                        "evidence_refs": [previous[source, kind, scope]["ref"], current[source, kind, scope]["ref"]]}
                       for source, kind, scope in sorted(current)]}


def build_context(value: object) -> dict:
    """Build an independent canonical packet or raise a fixed ContextError.

    Times are UTC Unix seconds; selection is half-open and at most one hour.
    No clock, randomness, I/O, provider call, mutation, or hidden truncation.
    The returned hash binds packet contents, not source authenticity or freshness.
    """
    _bounded_input(value)
    request = _object(value, {"schema", "subject", "window", "as_of", "sources", "records", "coverage", "comparison", "references"})
    _require(request["schema"] == INPUT_SCHEMA, "UNSUPPORTED_SCHEMA")
    subject = _address(request["subject"])
    window = _window(request["window"])
    as_of = _integer(request["as_of"], 0, MAX_TIME)
    _require(window["end"] <= as_of, "FUTURE_WINDOW")
    sources = {}
    for raw in _list(request["sources"], MAX_SOURCES):
        source = _object(raw, {"id", "kind", "expires_at"})
        identifier = _match(source["id"], r"[a-f0-9]{32}")
        _require(identifier not in sources, "DUPLICATE_SOURCE")
        kind = _enum(source["kind"], {"packets", "flows", "baselines"})
        expires = _integer(source["expires_at"], 0, MAX_TIME)
        _require(expires > as_of, "SOURCE_EXPIRED")
        sources[identifier] = {"id": identifier, "kind": kind, "expires_at": expires}
    coverage = _object(request["coverage"], {"truncated", "missing"})
    _require(type(coverage["truncated"]) is bool, "INVALID_COVERAGE")
    reasons = [_enum(reason, COVERAGE_REASONS) for reason in _list(coverage["missing"], len(COVERAGE_REASONS))]
    _require(len(set(reasons)) == len(reasons), "DUPLICATE_VALUE")
    coverage = {"truncated": coverage["truncated"], "missing": sorted(reasons)}
    used = set()
    records = [_record(row, subject, window, sources, used) for row in _list(request["records"], MAX_RECORDS)]
    _require(len({row["ref"] for row in records}) == len(records), "DUPLICATE_REFERENCE")
    findings = [f["ref"] for row in records for f in row.get("findings", [])]
    _require(len(set(findings)) == len(findings), "DUPLICATE_REFERENCE")
    _require(bool(records) == ("no_qualified_records" not in coverage["missing"]), "INVALID_COVERAGE")
    groups = [_group([r for r in records if (r["source"], r["kind"], r["scope_id"]) == (source, kind, scope)], source, kind, scope)
              for source, kind, scope in sorted({(r["source"], r["kind"], r["scope_id"]) for r in records})]
    comparison = _comparison(request["comparison"], subject, window, sources, used, groups, coverage)
    _require(used == sources.keys(), "UNUSED_SOURCE")
    references = []
    for raw in _list(request["references"], 3):
        ref = _object(raw, {"source", "edition", "id"})
        source = _enum(ref["source"], REFERENCE_PATTERNS)
        edition = _match(ref["edition"], r"[0-9]{4}\.[0-9]{2}(?:\.[0-9]{2})?")
        identifier = _match(ref["id"], REFERENCE_PATTERNS[source])
        references.append(f"{source}@{edition}:{identifier}")
    _require(len(set(references)) == len(references), "DUPLICATE_REFERENCE")
    packet = {"schema": CONTEXT_SCHEMA, "subject": subject, "window": window, "as_of": as_of,
              "groups": groups, "comparison": comparison, "coverage": coverage,
              "dependencies": [sources[key] for key in sorted(sources)], "reference_ids": sorted(references),
              "scope": "selected_records_only; no_capture_or_identity_guarantee"}
    packet["snapshot_sha256"] = sha256(_json(packet)).hexdigest()
    _require(len(_json(packet)) <= MAX_CONTEXT_BYTES, "CONTEXT_TOO_LARGE")
    return packet
