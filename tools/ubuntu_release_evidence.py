#!/usr/bin/env python3
"""Build or validate one bounded, non-publishing Ubuntu 24.04 evidence packet."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys


MAX_INPUT_BYTES = 262_144
MAX_DEPTH = 16
MAX_COLLECTION_ITEMS = 256
MAX_STRING_BYTES = 4_096
MAX_HOST_OUTPUT_BYTES = 4_096
CHECK_IDS = (
    "compile",
    "repository_tests",
    "cli_smoke",
    "loopback_browser",
    "sample_jsonl",
    "backup_restore",
    "native_failure_paths",
    "wheel_install_smoke",
    "sdist_install_smoke",
)
OPTIONAL_IDS = ("tshark", "suricata", "zeek", "ollama", "qwen_model")
ARTIFACT_IDS = ("wheel", "sdist")
EFFECT_IDS = (
    "network_fallback_used",
    "tag_created",
    "release_published",
    "package_uploaded",
    "deployment_performed",
    "service_installed",
    "firewall_changed",
    "sensor_started",
    "model_invoked",
    "restored_data_activated",
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
PYTHON_VERSION = re.compile(r"^3\.(11|12)\.[0-9]+$")
KERNEL = re.compile(r"^[A-Za-z0-9._+~-]+$")
SYSTEMD = re.compile(r"^[0-9]+(?: \([^\r\n]+\))?$")
REPOSITORY = "bartytime4life/MEGALODON"
ALLOWED_ORIGIN_URLS = {
    "https://github.com/bartytime4life/MEGALODON",
    "https://github.com/bartytime4life/MEGALODON.git",
    "git@github.com:bartytime4life/MEGALODON.git",
}


class EvidenceError(ValueError):
    """Closed validation failure without untrusted detail."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"UBUNTU_EVIDENCE:{code}")


def _fail(code: str) -> None:
    raise EvidenceError(code) from None


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


def read_manifest(path: Path) -> bytes:
    """Read at most one packet plus an excess-byte sentinel from a regular file."""
    # Nonblocking open lets a FIFO be rejected without waiting for a writer.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _fail("INPUT_INVALID")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_INPUT_BYTES:
        _fail("INPUT_LIMIT")
    return raw


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def digest(value: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _exact_keys(value, expected, reason="INPUT_INVALID") -> None:
    if type(value) is not dict or set(value) != set(expected):
        _fail(reason)


def _ordered_ids(rows, expected, reason) -> None:
    if type(rows) is not list or tuple(row.get("id") for row in rows if type(row) is dict) != expected:
        _fail(reason)


def validate(manifest: dict) -> dict:
    """Apply semantic controls that JSON Schema alone cannot express."""
    _bounded(manifest)
    _exact_keys(manifest, {
        "schema_version", "basis", "status", "repository", "source", "platform",
        "limits", "optional_components", "checks", "artifacts", "gates", "effects",
        "limitations", "generated_at",
    })
    if manifest["schema_version"] != "ubuntu-24.04-evidence-v1":
        _fail("INPUT_INVALID")
    if type(manifest["basis"]) is not str or manifest["basis"] not in {"synthetic_contract_fixture", "local_checkout", "github_actions"}:
        _fail("INPUT_INVALID")
    if type(manifest["status"]) is not str or manifest["status"] not in {"incomplete", "candidate_evidence"}:
        _fail("INPUT_INVALID")
    if manifest["repository"] != REPOSITORY:
        _fail("INPUT_INVALID")

    source = manifest["source"]
    _exact_keys(source, {"declared_commit", "observed_commit", "declared_tree", "observed_tree", "working_tree_dirty"})
    for key in ("declared_commit", "observed_commit", "declared_tree", "observed_tree"):
        if type(source[key]) is not str or HEX40.fullmatch(source[key]) is None:
            _fail("INPUT_INVALID")
    if source["working_tree_dirty"] is not False:
        _fail("SOURCE_DIRTY")
    if source["declared_commit"] != source["observed_commit"] or source["declared_tree"] != source["observed_tree"]:
        _fail("SOURCE_MISMATCH")

    platform_data = manifest["platform"]
    _exact_keys(platform_data, {
        "os_id", "version_id", "version_codename", "kernel_release", "architecture",
        "python_implementation", "python_version", "pip_version", "systemd_version",
    })
    if any(type(value) is not str for value in platform_data.values()):
        _fail("INPUT_INVALID")
    if (
        platform_data["os_id"], platform_data["version_id"], platform_data["version_codename"],
        platform_data["python_implementation"], platform_data["architecture"],
    ) not in {
        ("ubuntu", "24.04", "noble", "CPython", "x86_64"),
        ("ubuntu", "24.04", "noble", "CPython", "aarch64"),
    }:
        _fail("PLATFORM_UNSUPPORTED")
    for key in ("kernel_release", "python_version", "pip_version", "systemd_version"):
        if type(platform_data[key]) is not str or not platform_data[key]:
            _fail("INPUT_INVALID")
    if (
        len(platform_data["kernel_release"]) > 128
        or len(platform_data["pip_version"]) > 32
        or len(platform_data["systemd_version"]) > 64
        or KERNEL.fullmatch(platform_data["kernel_release"]) is None
        or PYTHON_VERSION.fullmatch(platform_data["python_version"]) is None
        or VERSION.fullmatch(platform_data["pip_version"]) is None
        or SYSTEMD.fullmatch(platform_data["systemd_version"]) is None
    ):
        _fail("INPUT_INVALID")

    expected_limits = {
        "max_input_bytes": 262144, "max_depth": 16, "max_collection_items": 256,
        "max_string_bytes": 4096, "max_command_output_bytes": 1048576,
        "max_checks": 9, "max_artifacts": 2,
    }
    if manifest["limits"] != expected_limits:
        _fail("INPUT_INVALID")

    _ordered_ids(manifest["optional_components"], OPTIONAL_IDS, "OPTIONAL_STATE")
    for item in manifest["optional_components"]:
        _exact_keys(item, {"id", "state", "health", "required_for_core"}, "OPTIONAL_STATE")
        if type(item["state"]) is not str or item["state"] not in {"absent", "disabled", "not_checked", "available_unqualified"}:
            _fail("OPTIONAL_STATE")
        if item["health"] != "unavailable" or item["required_for_core"] is not False:
            _fail("OPTIONAL_STATE")

    _ordered_ids(manifest["checks"], CHECK_IDS, "CHECK_SET")
    for item in manifest["checks"]:
        _exact_keys(item, {"id", "status", "output_bytes", "result_sha256", "notes"})
        if type(item["status"]) is not str or item["status"] not in {"passed", "failed", "not_run", "blocked"}:
            _fail("INPUT_INVALID")
        if type(item["output_bytes"]) is not int or not 0 <= item["output_bytes"] <= 1_048_576:
            _fail("INPUT_INVALID")
        if type(item["notes"]) is not str or len(item["notes"]) > 512:
            _fail("INPUT_INVALID")
        result_digest = item["result_sha256"]
        if item["status"] == "passed":
            if type(result_digest) is not str or DIGEST.fullmatch(result_digest) is None:
                _fail("INPUT_INVALID")
        elif result_digest is not None:
            _fail("INPUT_INVALID")

    _ordered_ids(manifest["artifacts"], ARTIFACT_IDS, "ARTIFACT_SET")
    for item in manifest["artifacts"]:
        _exact_keys(item, {"id", "status", "sha256", "size_bytes", "published"}, "ARTIFACT_SET")
        if item["published"] is not False:
            _fail("AUTHORITY_CLAIM")
        if type(item["status"]) is not str:
            _fail("ARTIFACT_SET")
        if item["status"] == "built_ephemeral":
            if type(item["sha256"]) is not str or DIGEST.fullmatch(item["sha256"]) is None:
                _fail("ARTIFACT_SET")
            if type(item["size_bytes"]) is not int or not 1 <= item["size_bytes"] <= 67_108_864:
                _fail("ARTIFACT_SET")
        elif item["status"] in {"not_run", "blocked"}:
            if item["sha256"] is not None or item["size_bytes"] is not None:
                _fail("ARTIFACT_SET")
        else:
            _fail("ARTIFACT_SET")

    gates = manifest["gates"]
    _exact_keys(gates, {"license", "operator_recovery", "sbom", "provenance", "release_authority"}, "AUTHORITY_CLAIM")
    # Preserve old receipts without treating their historical blocker as current.
    if gates["license"] not in (
        {"status": "blocked", "blocker": "https://github.com/bartytime4life/MEGALODON/issues/255"},
        {"status": "not_assessed", "blocker": None},
    ):
        _fail("AUTHORITY_CLAIM")
    expected_gates = {
        "license": gates["license"],
        "operator_recovery": "not_run", "sbom": "not_run", "provenance": "not_run",
        "release_authority": "not_authorized",
    }
    if gates != expected_gates:
        _fail("AUTHORITY_CLAIM")
    if type(manifest["effects"]) is not dict or set(manifest["effects"]) != set(EFFECT_IDS):
        _fail("AUTHORITY_CLAIM")
    if any(value is not False for value in manifest["effects"].values()):
        _fail("AUTHORITY_CLAIM")
    if (
        type(manifest["limitations"]) is not list or not 4 <= len(manifest["limitations"]) <= 16
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

    if manifest["status"] == "candidate_evidence":
        if manifest["basis"] == "synthetic_contract_fixture":
            _fail("CANDIDATE_INCOMPLETE")
        if any(item["status"] != "passed" for item in manifest["checks"]):
            _fail("CANDIDATE_INCOMPLETE")
        if any(item["status"] != "built_ephemeral" for item in manifest["artifacts"]):
            _fail("CANDIDATE_INCOMPLETE")
    return deepcopy(manifest)


def _run_fixed(argv: list[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(
            argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("HOST_TOOL")
    if len(completed.stdout) > MAX_HOST_OUTPUT_BYTES:
        _fail("HOST_TOOL")
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        _fail("HOST_TOOL")


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    try:
        raw = path.read_bytes()
    except OSError:
        _fail("PLATFORM_UNSUPPORTED")
    if len(raw) > 16_384:
        _fail("PLATFORM_UNSUPPORTED")
    result = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ID", "VERSION_ID", "VERSION_CODENAME"}:
            result[key] = value.strip().strip('"')
    return result


def collect(checkout: Path, declared_commit: str, declared_tree: str) -> dict:
    """Collect local identity only; intentionally leave every execution check not-run."""
    checkout = checkout.resolve(strict=True)
    observed_commit = _run_fixed(["git", "rev-parse", "--verify", "HEAD"], checkout)
    observed_tree = _run_fixed(["git", "rev-parse", "--verify", "HEAD^{tree}"], checkout)
    status = _run_fixed(["git", "status", "--porcelain", "--untracked-files=normal"], checkout)
    origin = _run_fixed(["git", "remote", "get-url", "origin"], checkout)
    if origin not in ALLOWED_ORIGIN_URLS:
        _fail("SOURCE_REPOSITORY")
    systemd_lines = _run_fixed(["systemd", "--version"], checkout).splitlines()
    if not systemd_lines:
        _fail("HOST_TOOL")
    systemd = systemd_lines[0]
    if not systemd.startswith("systemd "):
        _fail("PLATFORM_UNSUPPORTED")
    release = _os_release()
    manifest = {
        "schema_version": "ubuntu-24.04-evidence-v1",
        "basis": "local_checkout",
        "status": "incomplete",
        "repository": REPOSITORY,
        "source": {
            "declared_commit": declared_commit,
            "observed_commit": observed_commit,
            "declared_tree": declared_tree,
            "observed_tree": observed_tree,
            "working_tree_dirty": bool(status),
        },
        "platform": {
            "os_id": release.get("ID", ""),
            "version_id": release.get("VERSION_ID", ""),
            "version_codename": release.get("VERSION_CODENAME", ""),
            "kernel_release": platform.release(),
            "architecture": platform.machine(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "pip_version": importlib.metadata.version("pip"),
            "systemd_version": systemd.removeprefix("systemd "),
        },
        "limits": {
            "max_input_bytes": 262144, "max_depth": 16, "max_collection_items": 256,
            "max_string_bytes": 4096, "max_command_output_bytes": 1048576,
            "max_checks": 9, "max_artifacts": 2,
        },
        "optional_components": [
            {"id": item, "state": "not_checked", "health": "unavailable", "required_for_core": False}
            for item in OPTIONAL_IDS
        ],
        "checks": [
            {"id": item, "status": "not_run", "output_bytes": 0, "result_sha256": None,
             "notes": "Collector does not execute this check."}
            for item in CHECK_IDS
        ],
        "artifacts": [
            {"id": item, "status": "not_run", "sha256": None, "size_bytes": None, "published": False}
            for item in ARTIFACT_IDS
        ],
        "gates": {
            "license": {"status": "not_assessed", "blocker": None},
            "operator_recovery": "not_run", "sbom": "not_run", "provenance": "not_run",
            "release_authority": "not_authorized",
        },
        "effects": {item: False for item in EFFECT_IDS},
        "limitations": [
            "Local identity collection only; no repository test or build was run.",
            "Optional component presence and health were not inspected.",
            "License metadata and artifact redistribution requirements were not inspected by this collector.",
            "No tag, release, upload, deployment, service, sensor, model, firewall action, or restored-data activation occurred.",
        ],
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    return validate(manifest)


def verify_packet(packet: dict, expected_commit: str, expected_tree: str) -> dict:
    """Verify packet consistency against external pins, without authenticating it."""
    for expected in (expected_commit, expected_tree):
        if type(expected) is not str or HEX40.fullmatch(expected) is None:
            _fail("INPUT_INVALID")
    _bounded(packet)
    _exact_keys(packet, {"schema_version", "status", "manifest_sha256", "manifest"}, "PACKET_INVALID")
    if (
        packet["schema_version"] != "ubuntu-24.04-evidence-validation-v1"
        or packet["status"] != "validated"
        or type(packet["manifest_sha256"]) is not str
        or DIGEST.fullmatch(packet["manifest_sha256"]) is None
    ):
        _fail("PACKET_INVALID")
    manifest = validate(packet["manifest"])
    if packet["manifest_sha256"] != digest(manifest):
        _fail("DIGEST_MISMATCH")
    if (
        manifest["source"]["observed_commit"] != expected_commit
        or manifest["source"]["observed_tree"] != expected_tree
    ):
        _fail("SOURCE_MISMATCH")
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    group = result.add_subparsers(dest="command", required=True)
    verify = group.add_parser("validate", allow_abbrev=False)
    verify.add_argument("manifest")
    packet = group.add_parser("verify-packet", allow_abbrev=False)
    packet.add_argument("packet")
    packet.add_argument("--expected-commit", required=True)
    packet.add_argument("--expected-tree", required=True)
    capture = group.add_parser("collect", allow_abbrev=False)
    capture.add_argument("--checkout", default=".")
    capture.add_argument("--declared-commit", required=True)
    capture.add_argument("--declared-tree", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            raw = read_manifest(Path(args.manifest))
            manifest = validate(load(raw))
        elif args.command == "verify-packet":
            packet = load(read_manifest(Path(args.packet)))
            manifest = verify_packet(packet, args.expected_commit, args.expected_tree)
        else:
            manifest = collect(Path(args.checkout), args.declared_commit, args.declared_tree)
        result = {
            "schema_version": "ubuntu-24.04-evidence-validation-v1",
            "status": "validated",
            "manifest_sha256": digest(manifest),
            "manifest": manifest,
        }
        print(canonical(result).decode("utf-8"))
        return 0
    except (EvidenceError, OSError) as exc:
        code = exc.code if isinstance(exc, EvidenceError) else "INPUT_INVALID"
        print(json.dumps({
            "schema_version": "ubuntu-24.04-evidence-validation-v1",
            "status": "blocked",
            "reason": code,
        }, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
