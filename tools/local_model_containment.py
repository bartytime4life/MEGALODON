#!/usr/bin/env python3
"""Build or validate one bounded local-model containment acceptance packet.

This is the future operator-owned acceptance gate #261 asks for, expressed the
same way the Ubuntu release-evidence contract expresses missing evidence: a
closed, machine-readable shape that starts out honestly empty. It never
invokes a model, installs or starts Ollama, selects an artifact, contacts a
network, or grants detection/action authority. Right now no operator has
approved an exact local model alias/artifact, so ``collect()`` can only ever
produce the fixed ``unbound`` packet below; a future change adds real
inspection once that approval exists.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_INPUT_BYTES = 65_536
MAX_DEPTH = 12
MAX_COLLECTION_ITEMS = 64
MAX_STRING_BYTES = 2_048
REPOSITORY = "bartytime4life/MEGALODON"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
MODEL_ALIAS = re.compile(r"^local:qwen-[A-Za-z0-9._-]{1,96}$")
ADVERSARIAL_CATEGORIES = (
    "injection", "fabricated_evidence_ids", "unicode_control_text", "privacy",
    "exhaustion", "cancellation", "out_of_distribution",
)
WRAPPER_STATES = {"literal_loopback_only": {"not_checked", "verified", "failed"},
                   "outbound_deny_test": {"not_run", "passed", "failed"},
                   "effective_no_cloud_configuration": {"unknown", "verified", "failed"}}
PROCESS_STATES = {"identity_verified": {"not_checked", "verified", "failed"},
                   "lifecycle_observed": {"not_observed", "observed"},
                   "concurrency_slot_rejection": {"not_run", "passed", "failed"},
                   "cancellation_timeout": {"not_run", "passed", "failed"},
                   "filesystem_mutation_absent": {"not_checked", "verified", "failed"},
                   "host_wide_concurrency_absent": {"not_checked", "verified", "failed"}}
EFFECT_IDS = ("network_access_performed", "model_installed", "model_started",
              "artifact_selected", "detector_authority_granted", "action_authority_granted")


class ContainmentError(ValueError):
    """Closed validation failure without untrusted detail."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"LOCAL_MODEL_CONTAINMENT:{code}")


def _fail(code: str) -> None:
    raise ContainmentError(code) from None


def _reject_constant(_value: str):
    raise ValueError("non-finite value")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _bounded(value, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        _fail("INPUT_LIMIT")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            _fail("INPUT_INVALID")
        if size > MAX_STRING_BYTES:
            _fail("INPUT_LIMIT")
        return
    if type(value) is list:
        if len(value) > MAX_COLLECTION_ITEMS:
            _fail("INPUT_LIMIT")
        for item in value:
            _bounded(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_COLLECTION_ITEMS:
            _fail("INPUT_LIMIT")
        for key, item in value.items():
            if type(key) is not str:
                _fail("INPUT_INVALID")
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
        return
    _fail("INPUT_INVALID")


def load(raw: bytes) -> dict:
    if len(raw) > MAX_INPUT_BYTES:
        _fail("INPUT_LIMIT")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except RecursionError:
        _fail("INPUT_LIMIT")
    except (UnicodeError, ValueError, json.JSONDecodeError):
        _fail("INPUT_INVALID")
    if type(value) is not dict:
        _fail("INPUT_INVALID")
    _bounded(value)
    return value


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def digest(value: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _exact_keys(value, expected, reason="INPUT_INVALID") -> None:
    if type(value) is not dict or set(value) != set(expected):
        _fail(reason)


def _enum_block(value, states: dict, reason="INPUT_INVALID") -> None:
    _exact_keys(value, states.keys(), reason)
    for key, allowed in states.items():
        if type(value[key]) is not str or value[key] not in allowed:
            _fail(reason)


def validate(manifest: dict) -> dict:
    """Apply semantic controls that JSON Schema alone cannot express."""
    _bounded(manifest)
    _exact_keys(manifest, {
        "schema_version", "basis", "status", "repository", "model_binding",
        "wrapper_reachability", "process_boundary", "adversarial_corpus",
        "evidence_retention", "gates", "effects", "limitations", "generated_at",
    })
    if manifest["schema_version"] != "local-model-containment-acceptance-v1":
        _fail("INPUT_INVALID")
    if type(manifest["basis"]) is not str or manifest["basis"] not in {"synthetic_contract_fixture", "collector_output"}:
        _fail("INPUT_INVALID")
    if type(manifest["status"]) is not str or manifest["status"] not in {"unbound", "incomplete", "candidate_evidence"}:
        _fail("INPUT_INVALID")
    if manifest["repository"] != REPOSITORY:
        _fail("INPUT_INVALID")

    binding = manifest["model_binding"]
    if manifest["status"] == "unbound":
        if binding is not None:
            _fail("BINDING_UNEXPECTED")
    else:
        if type(binding) is not dict:
            _fail("BINDING_REQUIRED")
        _exact_keys(binding, {"model_alias", "artifact_sha256", "registry_fingerprint_sha256",
                               "operator_approved"})
        if (type(binding["model_alias"]) is not str
                or MODEL_ALIAS.fullmatch(binding["model_alias"]) is None):
            _fail("BINDING_REQUIRED")
        for key in ("artifact_sha256", "registry_fingerprint_sha256"):
            if type(binding[key]) is not str or HEX64.fullmatch(binding[key]) is None:
                _fail("BINDING_REQUIRED")
        if binding["operator_approved"] is not True:
            _fail("BINDING_REQUIRED")

    wrapper = manifest["wrapper_reachability"]
    _enum_block(wrapper, WRAPPER_STATES, "WRAPPER_STATE")
    process = manifest["process_boundary"]
    _enum_block(process, PROCESS_STATES, "PROCESS_STATE")

    corpus = manifest["adversarial_corpus"]
    _exact_keys(corpus, {"corpus_id", "categories_covered", "total_cases",
                          "cases_passed", "cases_failed"}, "CORPUS_STATE")
    if corpus["corpus_id"] is not None and (
        type(corpus["corpus_id"]) is not str or not 1 <= len(corpus["corpus_id"]) <= 128
    ):
        _fail("CORPUS_STATE")
    covered = corpus["categories_covered"]
    if (type(covered) is not list or any(type(item) is not str for item in covered)
            or len(set(covered)) != len(covered)
            or not set(covered) <= set(ADVERSARIAL_CATEGORIES)):
        _fail("CORPUS_STATE")
    for key in ("total_cases", "cases_passed", "cases_failed"):
        if type(corpus[key]) is not int or not 0 <= corpus[key] <= 100_000:
            _fail("CORPUS_STATE")
    if corpus["cases_passed"] + corpus["cases_failed"] != corpus["total_cases"]:
        _fail("CORPUS_STATE")

    retention = manifest["evidence_retention"]
    _exact_keys(retention, {"privacy_minimized_ids_only", "raw_advisory_text_retained"})
    if retention["privacy_minimized_ids_only"] is not True or retention["raw_advisory_text_retained"] is not False:
        _fail("RETENTION_CLAIM")

    gates = manifest["gates"]
    _exact_keys(gates, {"operator_model_selection", "independent_security_review"})
    if type(gates["operator_model_selection"]) is not str or gates["operator_model_selection"] not in {"blocked", "met"}:
        _fail("INPUT_INVALID")
    if type(gates["independent_security_review"]) is not str or gates["independent_security_review"] not in {"not_recorded", "recorded"}:
        _fail("INPUT_INVALID")

    if type(manifest["effects"]) is not dict or set(manifest["effects"]) != set(EFFECT_IDS):
        _fail("AUTHORITY_CLAIM")
    if any(value is not False for value in manifest["effects"].values()):
        _fail("AUTHORITY_CLAIM")

    if (
        type(manifest["limitations"]) is not list or not 3 <= len(manifest["limitations"]) <= 16
        or any(type(item) is not str or not item or len(item) > 512 for item in manifest["limitations"])
        or len(set(manifest["limitations"])) != len(manifest["limitations"])
    ):
        _fail("INPUT_INVALID")
    generated_at = manifest["generated_at"]
    if type(generated_at) is not str or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", generated_at,
    ) is None:
        _fail("INPUT_INVALID")
    try:
        datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail("INPUT_INVALID")

    if manifest["status"] == "unbound":
        if (
            wrapper != {"literal_loopback_only": "not_checked", "outbound_deny_test": "not_run",
                        "effective_no_cloud_configuration": "unknown"}
            or process != {
                "identity_verified": "not_checked", "lifecycle_observed": "not_observed",
                "concurrency_slot_rejection": "not_run", "cancellation_timeout": "not_run",
                "filesystem_mutation_absent": "not_checked", "host_wide_concurrency_absent": "not_checked",
            }
            or corpus["corpus_id"] is not None or covered or corpus["total_cases"] != 0
            or gates != {"operator_model_selection": "blocked", "independent_security_review": "not_recorded"}
        ):
            _fail("UNBOUND_STATE_MUST_BE_EMPTY")

    if manifest["status"] == "candidate_evidence":
        if manifest["basis"] == "synthetic_contract_fixture":
            _fail("CANDIDATE_INCOMPLETE")
        if any(value == "failed" for value in wrapper.values()) or any(value == "failed" for value in process.values()):
            _fail("CANDIDATE_INCOMPLETE")
        if (
            wrapper["literal_loopback_only"] != "verified"
            or wrapper["outbound_deny_test"] != "passed"
            or wrapper["effective_no_cloud_configuration"] != "verified"
            or process["identity_verified"] != "verified"
            or process["lifecycle_observed"] != "observed"
            or process["concurrency_slot_rejection"] != "passed"
            or process["cancellation_timeout"] != "passed"
            or process["filesystem_mutation_absent"] != "verified"
            or process["host_wide_concurrency_absent"] != "verified"
        ):
            _fail("CANDIDATE_INCOMPLETE")
        if (corpus["corpus_id"] is None or set(covered) != set(ADVERSARIAL_CATEGORIES)
                or corpus["cases_failed"] != 0 or corpus["cases_passed"] < 1):
            _fail("CANDIDATE_INCOMPLETE")
        if gates != {"operator_model_selection": "met", "independent_security_review": "recorded"}:
            _fail("CANDIDATE_INCOMPLETE")
    return deepcopy(manifest)


def collect() -> dict:
    """No operator-approved model alias/artifact exists; report the fixed unbound state."""
    manifest = {
        "schema_version": "local-model-containment-acceptance-v1",
        "basis": "collector_output",
        "status": "unbound",
        "repository": REPOSITORY,
        "model_binding": None,
        "wrapper_reachability": {
            "literal_loopback_only": "not_checked", "outbound_deny_test": "not_run",
            "effective_no_cloud_configuration": "unknown",
        },
        "process_boundary": {
            "identity_verified": "not_checked", "lifecycle_observed": "not_observed",
            "concurrency_slot_rejection": "not_run", "cancellation_timeout": "not_run",
            "filesystem_mutation_absent": "not_checked", "host_wide_concurrency_absent": "not_checked",
        },
        "adversarial_corpus": {
            "corpus_id": None, "categories_covered": [], "total_cases": 0,
            "cases_passed": 0, "cases_failed": 0,
        },
        "evidence_retention": {
            "privacy_minimized_ids_only": True, "raw_advisory_text_retained": False,
        },
        "gates": {"operator_model_selection": "blocked", "independent_security_review": "not_recorded"},
        "effects": {item: False for item in EFFECT_IDS},
        "limitations": [
            "No owner-approved exact local model alias or artifact digest is recorded.",
            "No wrapper reachability, process-boundary, or adversarial-corpus check has been run.",
            "This collector performs no host inspection; it reports the fixed absence of a binding.",
        ],
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    return validate(manifest)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    group = result.add_subparsers(dest="command", required=True)
    verify = group.add_parser("validate", allow_abbrev=False)
    verify.add_argument("manifest")
    group.add_parser("collect", allow_abbrev=False)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            raw = Path(args.manifest).read_bytes()
            manifest = validate(load(raw))
        else:
            manifest = collect()
        result = {
            "schema_version": "local-model-containment-acceptance-validation-v1",
            "status": "validated",
            "manifest_sha256": digest(manifest),
            "manifest": manifest,
        }
        print(canonical(result).decode("utf-8"))
        return 0
    except (ContainmentError, OSError) as exc:
        code = exc.code if isinstance(exc, ContainmentError) else "INPUT_INVALID"
        print(json.dumps({
            "schema_version": "local-model-containment-acceptance-validation-v1",
            "status": "blocked",
            "reason": code,
        }, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
