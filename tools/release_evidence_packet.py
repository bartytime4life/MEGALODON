#!/usr/bin/env python3
"""Generate or verify one non-publishing MEGALODON release-evidence packet."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import uuid


MAX_ARTIFACT_BYTES = 67_108_864
MAX_PACKET_FILE_BYTES = 262_144
PACKAGE_NAME = "megalodon-defense"
DISTRIBUTION_NAME = "megalodon_defense"
REPOSITORY = "bartytime4life/MEGALODON"
REPOSITORY_URL = "https://github.com/bartytime4life/MEGALODON"
BUILDER_URI = REPOSITORY_URL + "/.github/workflows/ci.yml"
PACKET_FILES = (
    "candidate-evidence.json",
    "megalodon.cdx.json",
    "provenance.intoto.json",
    "packet.json",
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

EFFECTS = {
    "network_used": False,
    "artifact_built": False,
    "package_installed": False,
    "tag_created": False,
    "release_published": False,
    "package_uploaded": False,
    "deployment_performed": False,
}
PRIVACY = {
    "included": [
        "source_commit",
        "source_tree",
        "package_name_and_version",
        "artifact_basenames_sizes_and_sha256",
        "document_sha256",
        "generation_timestamp",
    ],
    "excluded": [
        "absolute_paths",
        "usernames",
        "hostnames",
        "environment_variables",
        "command_lines",
        "logs",
        "telemetry",
        "credentials",
    ],
}


def _load_identity_tool():
    path = Path(__file__).with_name("ubuntu_release_evidence.py")
    spec = importlib.util.spec_from_file_location("_megalodon_ubuntu_release_evidence", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("identity verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity = _load_identity_tool()


class PacketError(ValueError):
    """Closed packet failure that never includes an untrusted value."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"RELEASE_EVIDENCE_PACKET:{code}")


def _fail(code: str) -> None:
    raise PacketError(code) from None


def _exact_keys(value, expected, code="PACKET_INVALID") -> None:
    if type(value) is not dict or set(value) != set(expected):
        _fail(code)


def _canonical(value: dict) -> bytes:
    return identity.canonical(value) + b"\n"


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _timestamp(value: str) -> str:
    if type(value) is not str or TIMESTAMP.fullmatch(value) is None:
        _fail("INPUT_INVALID")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail("INPUT_INVALID")
    return value


def _version(value: str) -> str:
    if type(value) is not str or VERSION.fullmatch(value) is None:
        _fail("INPUT_INVALID")
    return value


def _read_regular(path: Path, maximum: int, code: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail(code)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            _fail(code)
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        _fail(code)
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
        _fail(code)
    return raw


def _load_json(raw: bytes, code="PACKET_INVALID") -> dict:
    try:
        return identity.load(raw)
    except identity.EvidenceError:
        _fail(code)


def _artifact(path: Path, artifact_id: str, expected_name: str) -> dict:
    if path.name != expected_name:
        _fail("ARTIFACT_INVALID")
    raw = _read_regular(path, MAX_ARTIFACT_BYTES, "ARTIFACT_INVALID")
    if not raw:
        _fail("ARTIFACT_INVALID")
    return {
        "id": artifact_id,
        "name": expected_name,
        "sha256": _sha256(raw),
        "size_bytes": len(raw),
        "published": False,
    }


def _artifact_names(version: str) -> dict[str, str]:
    return {
        "wheel": f"{DISTRIBUTION_NAME}-{version}-py3-none-any.whl",
        "sdist": f"{DISTRIBUTION_NAME}-{version}.tar.gz",
    }


def _candidate(path: Path, expected_commit: str, expected_tree: str):
    raw = _read_regular(path, identity.MAX_INPUT_BYTES, "CANDIDATE_INVALID")
    wrapper = _load_json(raw, "CANDIDATE_INVALID")
    try:
        manifest = identity.verify_packet(wrapper, expected_commit, expected_tree)
    except identity.EvidenceError as exc:
        if exc.code == "SOURCE_MISMATCH":
            _fail("SOURCE_MISMATCH")
        _fail("CANDIDATE_INVALID")
    if manifest["basis"] != "github_actions" or manifest["status"] != "candidate_evidence":
        _fail("CANDIDATE_INCOMPLETE")
    canonical = _canonical(wrapper)
    if raw != canonical:
        _fail("NONCANONICAL_JSON")
    return wrapper, manifest, canonical


def _match_candidate_artifacts(manifest: dict, artifacts: list[dict]) -> None:
    expected = {row["id"]: row for row in manifest["artifacts"]}
    if set(expected) != {"wheel", "sdist"}:
        _fail("CANDIDATE_INCOMPLETE")
    for artifact in artifacts:
        row = expected[artifact["id"]]
        if (
            row["status"] != "built_ephemeral"
            or row["published"] is not False
            or row["sha256"] != artifact["sha256"]
            or row["size_bytes"] != artifact["size_bytes"]
        ):
            _fail("ARTIFACT_MISMATCH")


def _cyclonedx(
    *, version: str, generated_at: str, manifest: dict, artifacts: list[dict],
) -> dict:
    root_ref = f"pkg:pypi/{PACKAGE_NAME}@{version}"
    seed = "|".join([
        manifest["source"]["observed_commit"],
        manifest["source"]["observed_tree"],
        version,
        *(artifact["sha256"] for artifact in artifacts),
        generated_at,
    ])
    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "MEGALODON release-evidence packet generator",
                    "version": "1",
                }],
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": PACKAGE_NAME,
                "version": version,
                "purl": root_ref,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "externalReferences": [{
                    "type": "vcs",
                    "url": REPOSITORY_URL + "/tree/" + manifest["source"]["observed_commit"],
                }],
                "properties": [
                    {"name": "megalodon:source:commit", "value": manifest["source"]["observed_commit"]},
                    {"name": "megalodon:source:tree", "value": manifest["source"]["observed_tree"]},
                    {"name": "megalodon:dependency-scope", "value": "declared-runtime-dependencies-only"},
                ],
            },
        },
        "components": [
            {
                "type": "file",
                "bom-ref": "artifact:" + artifact["id"] + ":" + artifact["sha256"],
                "name": artifact["name"],
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": artifact["sha256"].removeprefix("sha256:")}],
                "properties": [
                    {"name": "megalodon:artifact:kind", "value": artifact["id"]},
                    {"name": "megalodon:artifact:published", "value": "false"},
                ],
            }
            for artifact in artifacts
        ],
        "dependencies": [{"ref": root_ref, "dependsOn": []}],
        "properties": [
            {"name": "megalodon:evidence:status", "value": "generated-unreviewed"},
            {"name": "megalodon:evidence:publication", "value": "not-published"},
        ],
    }


def _provenance(
    *, version: str, manifest: dict, artifacts: list[dict], candidate_sha256: str,
) -> dict:
    commit = manifest["source"]["observed_commit"]
    tree = manifest["source"]["observed_tree"]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": artifact["name"], "digest": {"sha256": artifact["sha256"].removeprefix("sha256:")}}
            for artifact in artifacts
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": REPOSITORY_URL + "/blob/" + commit + "/docs/ubuntu-release-evidence.md#release-evidence-packet",
                "externalParameters": {
                    "repository": REPOSITORY_URL,
                    "sourceCommit": commit,
                    "sourceTree": tree,
                    "workflow": ".github/workflows/ci.yml",
                    "job": "wheel-smoke",
                    "package": PACKAGE_NAME,
                    "version": version,
                    "candidateEvidenceSha256": candidate_sha256.removeprefix("sha256:"),
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "name": "MEGALODON source commit",
                        "uri": f"git+{REPOSITORY_URL}.git@{commit}",
                        "digest": {"sha1": commit},
                    },
                    {
                        "name": "MEGALODON source tree",
                        "uri": f"git+{REPOSITORY_URL}.git@{commit}#tree",
                        "digest": {"sha1": tree},
                    },
                    {
                        "name": "candidate-evidence.json",
                        "digest": {"sha256": candidate_sha256.removeprefix("sha256:")},
                    },
                ],
            },
            "runDetails": {"builder": {"id": BUILDER_URI + "@" + commit}},
        },
    }


def _packet_manifest(
    *, version: str, generated_at: str, manifest: dict, artifacts: list[dict],
    candidate_bytes: bytes, candidate_manifest_sha256: str, sbom_bytes: bytes,
    provenance_bytes: bytes,
) -> dict:
    return {
        "schema_version": "megalodon-release-evidence-packet-v1",
        "status": "generated_unreviewed",
        "repository": REPOSITORY,
        "source": {
            "commit": manifest["source"]["observed_commit"],
            "tree": manifest["source"]["observed_tree"],
        },
        "package": {
            "name": PACKAGE_NAME,
            "version": version,
            "license_expression": "Apache-2.0",
            "runtime_dependencies": [],
        },
        "candidate_evidence": {
            "name": "candidate-evidence.json",
            "sha256": _sha256(candidate_bytes),
            "manifest_sha256": candidate_manifest_sha256,
        },
        "artifacts": artifacts,
        "documents": [
            {
                "id": "cyclonedx_sbom",
                "name": "megalodon.cdx.json",
                "media_type": "application/vnd.cyclonedx+json; version=1.7",
                "sha256": _sha256(sbom_bytes),
            },
            {
                "id": "slsa_provenance",
                "name": "provenance.intoto.json",
                "media_type": "application/vnd.in-toto+json",
                "sha256": _sha256(provenance_bytes),
            },
        ],
        "privacy": PRIVACY,
        "effects": EFFECTS,
        "limitations": [
            "Digest and shape binding is not a signature, identity authentication, or SLSA build-level claim.",
            "The SBOM covers the core package, its declared empty runtime dependency set, and the two built subjects; optional, build, test, OS, and browser components are excluded.",
            "The Apache-2.0 expression is the packet contract; independent artifact notice and license review remains required.",
            "No artifact was built, installed, tagged, published, uploaded, or deployed by this generator.",
        ],
        "generated_at": generated_at,
    }


def _validate_packet_header(packet: dict) -> tuple[str, str]:
    _exact_keys(packet, {
        "schema_version", "status", "repository", "source", "package",
        "candidate_evidence", "artifacts", "documents", "privacy", "effects",
        "limitations", "generated_at",
    })
    if (
        packet["schema_version"] != "megalodon-release-evidence-packet-v1"
        or packet["status"] != "generated_unreviewed"
        or packet["repository"] != REPOSITORY
    ):
        _fail("PACKET_INVALID")
    _exact_keys(packet["source"], {"commit", "tree"})
    if any(type(packet["source"][key]) is not str or HEX40.fullmatch(packet["source"][key]) is None for key in ("commit", "tree")):
        _fail("PACKET_INVALID")
    _exact_keys(packet["package"], {"name", "version", "license_expression", "runtime_dependencies"})
    if (
        packet["package"]["name"] != PACKAGE_NAME
        or packet["package"]["license_expression"] != "Apache-2.0"
        or packet["package"]["runtime_dependencies"] != []
    ):
        _fail("PACKET_INVALID")
    version = _version(packet["package"]["version"])
    generated_at = _timestamp(packet["generated_at"])
    return version, generated_at


def _directory_files(directory: Path) -> dict[str, Path]:
    if directory.is_symlink() or not directory.is_dir():
        _fail("FILE_SET")
    try:
        entries = {entry.name: entry for entry in os.scandir(directory)}
    except OSError:
        _fail("FILE_SET")
    if set(entries) != set(PACKET_FILES):
        _fail("FILE_SET")
    result = {}
    for name in PACKET_FILES:
        entry = entries[name]
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            _fail("FILE_SET")
        result[name] = Path(entry.path)
    return result


def _receipt(packet_bytes: bytes, packet: dict, operation: str) -> dict:
    return {
        "schema_version": "megalodon-release-evidence-verification-v1",
        "status": "binding_verified",
        "operation": operation,
        "authentication": "not_performed",
        "source": packet["source"],
        "artifacts": [
            {key: artifact[key] for key in ("id", "name", "sha256", "size_bytes")}
            for artifact in packet["artifacts"]
        ],
        "packet_manifest_sha256": _sha256(packet_bytes),
        "privacy": PRIVACY,
        "effects": EFFECTS,
    }


def verify_packet_directory(
    directory: Path, wheel: Path, sdist: Path, expected_commit: str, expected_tree: str,
    *, operation: str = "verified",
) -> dict:
    files = _directory_files(directory)
    raws = {
        name: _read_regular(path, MAX_PACKET_FILE_BYTES, "PACKET_INVALID")
        for name, path in files.items()
    }
    values = {name: _load_json(raw) for name, raw in raws.items()}
    for name, value in values.items():
        if raws[name] != _canonical(value):
            _fail("NONCANONICAL_JSON")

    candidate_wrapper = values["candidate-evidence.json"]
    try:
        candidate_manifest = identity.verify_packet(
            candidate_wrapper, expected_commit, expected_tree,
        )
    except identity.EvidenceError as exc:
        if exc.code == "SOURCE_MISMATCH":
            _fail("SOURCE_MISMATCH")
        _fail("CANDIDATE_INVALID")
    if candidate_manifest["basis"] != "github_actions" or candidate_manifest["status"] != "candidate_evidence":
        _fail("CANDIDATE_INCOMPLETE")

    packet = values["packet.json"]
    version, generated_at = _validate_packet_header(packet)
    if packet["source"] != {"commit": expected_commit, "tree": expected_tree}:
        _fail("SOURCE_MISMATCH")
    if generated_at < candidate_manifest["generated_at"]:
        _fail("PACKET_INVALID")
    names = _artifact_names(version)
    artifacts = [
        _artifact(wheel, "wheel", names["wheel"]),
        _artifact(sdist, "sdist", names["sdist"]),
    ]
    _match_candidate_artifacts(candidate_manifest, artifacts)

    candidate_bytes = raws["candidate-evidence.json"]
    sbom = _cyclonedx(
        version=version, generated_at=generated_at,
        manifest=candidate_manifest, artifacts=artifacts,
    )
    if values["megalodon.cdx.json"] != sbom:
        _fail("SBOM_MISMATCH")
    provenance = _provenance(
        version=version, manifest=candidate_manifest, artifacts=artifacts,
        candidate_sha256=_sha256(candidate_bytes),
    )
    if values["provenance.intoto.json"] != provenance:
        _fail("PROVENANCE_MISMATCH")
    expected_packet = _packet_manifest(
        version=version,
        generated_at=generated_at,
        manifest=candidate_manifest,
        artifacts=artifacts,
        candidate_bytes=candidate_bytes,
        candidate_manifest_sha256=candidate_wrapper["manifest_sha256"],
        sbom_bytes=raws["megalodon.cdx.json"],
        provenance_bytes=raws["provenance.intoto.json"],
    )
    if packet != expected_packet:
        _fail("BINDING_MISMATCH")
    return _receipt(raws["packet.json"], packet, operation)


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail("OUTPUT_INVALID")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically publish a completed directory without replacing any target."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        _fail("OUTPUT_INVALID")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100, os.fsencode(source), -100, os.fsencode(target), 1,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            _fail("OUTPUT_EXISTS")
        _fail("OUTPUT_INVALID")


def generate_packet(
    candidate: Path, wheel: Path, sdist: Path, output: Path, version: str,
    generated_at: str, expected_commit: str, expected_tree: str,
) -> dict:
    version = _version(version)
    generated_at = _timestamp(generated_at)
    if type(expected_commit) is not str or HEX40.fullmatch(expected_commit) is None:
        _fail("INPUT_INVALID")
    if type(expected_tree) is not str or HEX40.fullmatch(expected_tree) is None:
        _fail("INPUT_INVALID")
    candidate_wrapper, manifest, candidate_bytes = _candidate(
        candidate, expected_commit, expected_tree,
    )
    if generated_at < manifest["generated_at"]:
        _fail("INPUT_INVALID")
    names = _artifact_names(version)
    artifacts = [
        _artifact(wheel, "wheel", names["wheel"]),
        _artifact(sdist, "sdist", names["sdist"]),
    ]
    _match_candidate_artifacts(manifest, artifacts)
    sbom_bytes = _canonical(_cyclonedx(
        version=version, generated_at=generated_at, manifest=manifest, artifacts=artifacts,
    ))
    provenance_bytes = _canonical(_provenance(
        version=version, manifest=manifest, artifacts=artifacts,
        candidate_sha256=_sha256(candidate_bytes),
    ))
    packet_bytes = _canonical(_packet_manifest(
        version=version,
        generated_at=generated_at,
        manifest=manifest,
        artifacts=artifacts,
        candidate_bytes=candidate_bytes,
        candidate_manifest_sha256=candidate_wrapper["manifest_sha256"],
        sbom_bytes=sbom_bytes,
        provenance_bytes=provenance_bytes,
    ))
    payload = {
        "candidate-evidence.json": candidate_bytes,
        "megalodon.cdx.json": sbom_bytes,
        "provenance.intoto.json": provenance_bytes,
        "packet.json": packet_bytes,
    }

    parent = output.parent.resolve(strict=True)
    target = parent / output.name
    if output.name in {"", ".", ".."}:
        _fail("OUTPUT_INVALID")
    if target.exists() or target.is_symlink():
        _fail("OUTPUT_EXISTS")
    staging = Path(tempfile.mkdtemp(prefix=".megalodon-release-evidence-", dir=parent))
    os.chmod(staging, 0o700)
    try:
        for name in PACKET_FILES:
            _write_exclusive(staging / name, payload[name])
        receipt = verify_packet_directory(
            staging, wheel, sdist, expected_commit, expected_tree, operation="generated",
        )
        _rename_noreplace(staging, target)
        return receipt
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    commands = result.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", allow_abbrev=False)
    generate.add_argument("--candidate", required=True)
    generate.add_argument("--wheel", required=True)
    generate.add_argument("--sdist", required=True)
    generate.add_argument("--output", required=True)
    generate.add_argument("--package-version", required=True)
    generate.add_argument("--generated-at", required=True)
    generate.add_argument("--expected-commit", required=True)
    generate.add_argument("--expected-tree", required=True)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("packet")
    verify.add_argument("--wheel", required=True)
    verify.add_argument("--sdist", required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--expected-tree", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "generate":
            receipt = generate_packet(
                Path(args.candidate), Path(args.wheel), Path(args.sdist), Path(args.output),
                args.package_version, args.generated_at, args.expected_commit, args.expected_tree,
            )
        else:
            receipt = verify_packet_directory(
                Path(args.packet), Path(args.wheel), Path(args.sdist),
                args.expected_commit, args.expected_tree,
            )
        print(_canonical(receipt).decode("utf-8"), end="")
        return 0
    except PacketError as exc:
        code = exc.code
    except identity.EvidenceError:
        code = "CANDIDATE_INVALID"
    except OSError:
        code = "IO_ERROR"
    print(json.dumps({
        "schema_version": "megalodon-release-evidence-verification-v1",
        "status": "blocked",
        "reason": code,
    }, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
